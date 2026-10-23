"""OpenAPI/Swagger discovery and offline request-template generation."""

import json
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.module import Option
from fieldkit.modules.discovery_helpers import get_seed_urls, positive_limits

DOCUMENT_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/openapi.yaml",
    "/swagger.yaml",
)
HTTP_METHODS = {"get", "head", "post", "put", "patch", "delete", "options", "trace"}


def parse_document(body: bytes) -> dict:
    text = body.decode("utf-8-sig")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        # SafeLoader forbids construction of arbitrary Python objects.
        document = yaml.safe_load(text)
    if not isinstance(document, dict) or not (
        str(document.get("openapi", "")).startswith("3.") or document.get("swagger") == "2.0"
    ):
        raise ValueError("Not an OpenAPI 3.x or Swagger 2.0 document")
    if not isinstance(document.get("paths", {}), dict):
        raise ValueError("Document paths must be an object")
    return document


def local_object(document: dict, value, warnings: set, visited=()):
    """Resolve local JSON pointers only, detecting cycles and bounding depth."""
    if not isinstance(value, dict):
        return {}
    ref = value.get("$ref")
    if not ref:
        return value
    if not isinstance(ref, str) or not ref.startswith("#/"):
        warnings.add("External references were not fetched")
        return {}
    if ref in visited or len(visited) >= 12:
        warnings.add("Cyclic or deeply nested local reference was skipped")
        return {}
    target = document
    try:
        for token in ref[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            target = target[int(token)] if isinstance(target, list) else target[token]
    except (KeyError, IndexError, TypeError, ValueError):
        warnings.add("Unresolved local reference was skipped")
        return {}
    return local_object(document, target, warnings, (*visited, ref))


def server_urls(document, path_item, operation, document_url):
    if document.get("swagger") == "2.0":
        parsed = urlsplit(document_url)
        host = document.get("host") or parsed.netloc
        base_path = document.get("basePath") or "/"
        schemes = document.get("schemes") or [parsed.scheme]
        if (
            not isinstance(host, str)
            or not isinstance(base_path, str)
            or not isinstance(schemes, list)
        ):
            return []
        return [
            f"{scheme}://{host}/{base_path.strip('/')}"
            for scheme in schemes
            if isinstance(scheme, str) and scheme in {"http", "https"}
        ]
    servers = operation.get(
        "servers", path_item.get("servers", document.get("servers", [{"url": "/"}]))
    )
    urls = []
    for server in servers if isinstance(servers, list) else []:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            continue
        url = server["url"]
        variables = server.get("variables", {})
        if isinstance(variables, dict):
            for name, schema in variables.items():
                if isinstance(schema, dict) and isinstance(
                    schema.get("default"), (str, int, float)
                ):
                    url = url.replace("{" + str(name) + "}", str(schema["default"]))
        if "{" not in url:
            try:
                urls.append(urljoin(document_url, url))
            except ValueError:
                continue
    return urls


def operation_parameters(document, path_item, operation, warnings):
    parameters = {}
    for container in [path_item, operation]:
        items = container.get("parameters", [])
        if not isinstance(items, list):
            continue
        for item in items[:1000]:
            item = local_object(document, item, warnings)
            name, location = item.get("name"), item.get("in")
            if not isinstance(name, str) or not isinstance(location, str):
                continue
            schema = local_object(document, item.get("schema", {}), warnings)
            parameter_type = schema.get("type", item.get("type", "unknown"))
            parameters[name, location] = {
                "name": name,
                "in": location,
                "required": bool(item.get("required")),
                "type": parameter_type[:100] if isinstance(parameter_type, str) else "unknown",
            }
    request_body = local_object(document, operation.get("requestBody", {}), warnings)
    content = request_body.get("content", {})
    for media in list(content.values())[:20] if isinstance(content, dict) else []:
        if not isinstance(media, dict):
            continue
        schema = local_object(document, media.get("schema", {}), warnings)
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for name, raw_property in (
            list(properties.items())[:1000] if isinstance(properties, dict) else []
        ):
            prop = local_object(document, raw_property, warnings)
            if isinstance(name, str):
                parameter_type = prop.get("type", "unknown")
                parameters[name, "body"] = {
                    "name": name,
                    "in": "body",
                    "required": name in required if isinstance(required, list) else False,
                    "type": parameter_type[:100] if isinstance(parameter_type, str) else "unknown",
                }
    return list(parameters.values())


class APIInventory(NetworkModule):
    name = "web/api-inventory"
    description = "Catalog OpenAPI/Swagger operations and generate unexecuted request templates."
    options = COMMON_OPTIONS + (
        Option(
            "MAX_DOCUMENTS", int, 30, "Maximum specification candidates to fetch", "--max-documents"
        ),
        Option(
            "MAX_OPERATIONS", int, 1000, "Maximum operations in the inventory", "--max-operations"
        ),
        Option(
            "ONLY_CUSTOM", bool, False, "Only inspect --path and imported URLs", "--only-custom"
        ),
    )

    def validate(self, settings):
        positive_limits(settings, "MAX_DOCUMENTS", "MAX_OPERATIONS")
        if settings["ONLY_CUSTOM"] and not (settings["PATHS"] or settings["INVENTORY"]):
            raise ValueError("ONLY_CUSTOM requires PATHS or INVENTORY")

    async def assess(self, ctx):
        urls = get_seed_urls(ctx) if ctx.settings["PATHS"] or ctx.settings["INVENTORY"] else []
        if not ctx.settings["ONLY_CUSTOM"]:
            for base in ctx.targets:
                urls.extend(ctx.resolve(path, base) for path in DOCUMENT_PATHS)
        urls = list(dict.fromkeys(url for url in urls if url))
        templates = []
        seen = set()
        operations = 0
        for url in urls[: ctx.settings["MAX_DOCUMENTS"]]:
            response = await ctx.fetch(url)
            if response.error or response.status is None or not 200 <= response.status < 300:
                continue
            try:
                document = parse_document(response.body)
            except (ValueError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
                ctx.report["results"].append(
                    {
                        "kind": "api-document",
                        "url": url,
                        "recognized": False,
                        "detail": str(exc)[:300],
                        "evidence": response.evidence_id,
                    }
                )
                continue
            warnings = set()
            record = {
                "kind": "api-document",
                "url": url,
                "recognized": True,
                "version": document.get("openapi", document.get("swagger")),
                "evidence": response.evidence_id,
                "operations": 0,
            }
            ctx.report["results"].append(record)
            for path, raw_path_item in document.get("paths", {}).items():
                if operations >= ctx.settings["MAX_OPERATIONS"]:
                    break
                if not isinstance(path, str) or not path.startswith("/"):
                    continue
                path_item = local_object(document, raw_path_item, warnings)
                for method, raw_operation in path_item.items():
                    if method not in HTTP_METHODS or operations >= ctx.settings["MAX_OPERATIONS"]:
                        continue
                    operation = local_object(document, raw_operation, warnings)
                    if not isinstance(raw_operation, dict) or (
                        "$ref" in raw_operation and not operation
                    ):
                        continue
                    parameters = operation_parameters(document, path_item, operation, warnings)
                    security = operation.get("security", document.get("security", []))
                    security = (
                        [
                            {
                                str(name): [
                                    scope[:200] for scope in scopes[:100] if isinstance(scope, str)
                                ]
                                if isinstance(scopes, list)
                                else []
                                for name, scopes in requirement.items()
                            }
                            for requirement in security[:100]
                            if isinstance(requirement, dict)
                        ]
                        if isinstance(security, list)
                        else []
                    )
                    auth_schemes = sorted(
                        {
                            str(name)
                            for requirement in security
                            if isinstance(requirement, dict)
                            for name in requirement
                        }
                    )
                    for base in server_urls(document, path_item, operation, response.url):
                        try:
                            parsed = urlsplit(base)
                        except ValueError:
                            warnings.add("Invalid API server URL was omitted")
                            continue
                        full_url = urlunsplit(
                            parsed._replace(
                                path=parsed.path.rstrip("/") + path,
                                query="",
                                fragment="",
                            )
                        )
                        if not ctx.in_scope(full_url):
                            warnings.add("Out-of-scope API servers were omitted")
                            continue
                        key = method, full_url
                        if key in seen:
                            continue
                        seen.add(key)
                        endpoint = ctx.add_endpoint(
                            full_url,
                            method=method.upper(),
                            source=url,
                            parameters=parameters,
                            security=security,
                            authentication_schemes=auth_schemes,
                            authentication_optional=not security or {} in security,
                        )
                        if endpoint is None:
                            continue
                        request_body = local_object(
                            document, operation.get("requestBody", {}), warnings
                        )
                        content = request_body.get("content", {})
                        body_types = (
                            [str(key) for key in content] if isinstance(content, dict) else []
                        )
                        template = {
                            "method": method.upper(),
                            "url": full_url,
                            "query": {
                                p["name"]: "<VALUE>" for p in parameters if p["in"] == "query"
                            },
                            "headers": {
                                p["name"]: "<VALUE>" for p in parameters if p["in"] == "header"
                            },
                            "parameters": parameters,
                            "body": "<SUPPLY BODY>"
                            if body_types
                            or any(p["in"] in {"body", "formData"} for p in parameters)
                            else None,
                            "content_types": body_types,
                            "authentication_schemes": auth_schemes,
                            "source": url,
                            "executed": False,
                        }
                        templates.append(template)
                        ctx.report["results"].append(
                            {
                                "kind": "api-operation",
                                "method": method.upper(),
                                "url": full_url,
                                "parameters": parameters,
                                "authentication_schemes": auth_schemes,
                                "authentication_optional": not security or {} in security,
                                "evidence": response.evidence_id,
                            }
                        )
                        operations += 1
                        record["operations"] += 1
                        if operations >= ctx.settings["MAX_OPERATIONS"]:
                            break
            record["warnings"] = sorted(warnings)
        template_path = ctx.store.root / "request-templates.json"
        write_private(template_path, json.dumps(templates, indent=2) + "\n")
        ctx.report["results"].append(
            {
                "kind": "api-summary",
                "operations": operations,
                "templates_file": template_path.name,
                "limited": operations >= ctx.settings["MAX_OPERATIONS"]
                or len(urls) > ctx.settings["MAX_DOCUMENTS"],
                "note": "Templates are not executed; substitute values before use.",
            }
        )
