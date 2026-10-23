"""Request formats, explicit field edits and shared scoped HTTP execution."""

import base64
import copy
import json
import re
import time
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fieldkit.core.assessment import header_secrets
from fieldkit.core.redaction import SENSITIVE
from fieldkit.core.urls import normalize_url
from fieldkit.core.xml import parse_xml

METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}


def bounded_json(filename, maximum=1048576):
    with Path(filename).expanduser().open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("Request/config file exceeds byte limit")
    try:
        return json.loads(content)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid request/config JSON") from exc


def string_map(value, name):
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise ValueError(f"{name} must map strings to strings")
    if any(any(c in k + v for c in "\r\n\0") for k, v in value.items()):
        raise ValueError(f"{name} cannot contain control characters")
    return value


def validate_request(request):
    if not isinstance(request, dict) or not isinstance(request.get("url"), str):
        raise ValueError("Each request requires a URL string")
    request = copy.deepcopy(request)
    if not isinstance(request.get("method", "GET"), str):
        raise ValueError("HTTP method must be a string")
    method = request.get("method", "GET").upper()
    if method not in METHODS:
        raise ValueError("Unsupported HTTP method")
    request["method"] = method
    headers = string_map(request.get("headers", {}), "headers")
    if any(
        k.lower()
        in {"host", "transfer-encoding", "content-length", "connection", "proxy-authorization"}
        for k in headers
    ):
        raise ValueError("Host, proxy and framing header overrides are unsupported")
    if any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", k) for k in headers):
        raise ValueError("Invalid HTTP header name")
    string_map(request.get("cookies", {}), "cookies")
    for key in ("query", "form", "data"):
        if (
            key in request
            and request[key] is not None
            and not (
                isinstance(request[key], dict)
                and all(
                    isinstance(k, str) and isinstance(v, (str, int, float, bool))
                    for k, v in request[key].items()
                )
            )
        ):
            # Legacy session sequences can supply a string data body.
            if key != "data" or not isinstance(request[key], str):
                raise ValueError(f"{key} must map strings to scalar values")
    keys = [
        k
        for k in ("form", "json", "xml", "body", "body_base64", "data")
        if request.get(k) is not None
    ]
    if len(keys) > 1:
        raise ValueError("Specify exactly one body encoding")
    for key in ("body", "xml"):
        if request.get(key) is not None and not isinstance(request[key], str):
            raise ValueError(f"{key} must be a string")
    if request.get("xml") is not None:
        parse_xml(request["xml"].encode())
    if "body_base64" in request:
        if not isinstance(request["body_base64"], str):
            raise ValueError("body_base64 must be a Base64 string")
        try:
            base64.b64decode(request["body_base64"], validate=True)
        except ValueError as exc:
            raise ValueError("Invalid Base64 request body") from exc
    if "json" in request:
        try:
            json.dumps(request["json"], allow_nan=False)
        except (ValueError, TypeError, RecursionError) as exc:
            raise ValueError("JSON body must contain finite JSON values") from exc
    if "profile" in request and (not isinstance(request["profile"], str) or not request["profile"]):
        raise ValueError("Request profile must be a nonempty name")
    return request


def raw_request(text, base):
    raw = text.encode() if isinstance(text, str) else text
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition(b"\n\n")
    lines = head.decode("utf-8").splitlines()
    if not lines:
        raise ValueError("Empty raw HTTP request")
    match = re.fullmatch(r"([A-Z]+) (\S+) HTTP/1\.[01]", lines[0])
    if not match:
        raise ValueError("Raw request requires METHOD target HTTP/1.0 or 1.1")
    headers, host = {}, ""
    seen_headers = set()
    content_length = None
    for line in lines[1:]:
        key, colon, value = line.partition(":")
        if not colon or not key or line.startswith((" ", "\t")):
            raise ValueError("Malformed/folded raw HTTP header")
        key, value = key.strip(), value.strip()
        if key.lower() in seen_headers:
            raise ValueError("Duplicate raw headers are unsupported")
        seen_headers.add(key.lower())
        if key.lower() == "host":
            host = value
        elif key.lower() == "content-length":
            content_length = value
        else:
            headers[key] = value
    target = match[2]
    if target.startswith("/") and not target.startswith("//"):
        if not base:
            raise ValueError("Relative raw HTTP target requires --raw-url with explicit scheme")
        parsed = urlsplit(normalize_url(base))
        if host and host.lower() != parsed.netloc.lower():
            raise ValueError("Raw Host must match RAW_URL authority; use target hostnames")
        url = urlunsplit((parsed.scheme, parsed.netloc, *urlsplit(target)[2:]))
    else:
        url = normalize_url(target)
        if host and host.lower() != urlsplit(url).netloc.lower():
            raise ValueError("Raw Host disagrees with absolute request URL")
    if content_length is not None and (
        not content_length.isdigit() or int(content_length) != len(body)
    ):
        raise ValueError("Raw Content-Length disagrees with body bytes")
    request = {"id": "1", "method": match[1], "url": url, "headers": headers}
    media = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if separator and body:
        if "application/json" in media:
            try:
                request["json"] = json.loads(body)
            except ValueError as exc:
                raise ValueError("Malformed raw JSON body") from exc
        elif "application/x-www-form-urlencoded" in media:
            pairs = parse_qsl(body.decode(), keep_blank_values=True)
            if len(dict(pairs)) != len(pairs):
                raise ValueError("Repeated form keys require an explicit raw body")
            request["form"] = dict(pairs)
        elif "xml" in media:
            request["xml"] = body.decode()
        else:
            try:
                request["body"] = body.decode("utf-8")
            except UnicodeError:
                request["body_base64"] = base64.b64encode(body).decode()
    return validate_request(request)


def load_requests(filename, *, raw=False, base="", max_bytes=1048576):
    if raw:
        with Path(filename).expanduser().open("rb") as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("Raw request exceeds byte limit")
        return [raw_request(data, base)]
    value = bounded_json(filename, max_bytes)
    records = value.get("requests", [value]) if isinstance(value, dict) else value
    if not isinstance(records, list) or not records or len(records) > 1000:
        raise ValueError("Request JSON must be a request, list or {requests: [...]} (max 1000)")
    output = []
    seen = set()
    for index, record in enumerate(records, 1):
        record = validate_request(record)
        name = str(record.get("id", index))
        if not name or name in seen:
            raise ValueError("Request IDs must be unique")
        seen.add(name)
        record["id"] = name
        output.append(record)
    return output


def select_requests(records, names):
    if not names:
        raise ValueError("Explicit --request-id selection is required; imports do not execute")
    selected = [r for r in records if r["id"] in names]
    if set(names) != {r["id"] for r in selected}:
        raise ValueError("Unknown request ID")
    return selected


def json_pointer(document, pointer, value):
    if not pointer.startswith("/"):
        raise ValueError("JSON edit requires /path JSON pointer")
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]
    parent = document
    try:
        for token in tokens[:-1]:
            parent = parent[int(token)] if isinstance(parent, list) else parent[token]
        token = int(tokens[-1]) if isinstance(parent, list) else tokens[-1]
        previous = parent[token]
        parent[token] = value
        return previous
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ValueError("JSON injection location does not exist") from exc


def edit_request(request, location, value):
    output = copy.deepcopy(request)
    kind, separator, name = location.partition(":")
    if not separator:
        raise ValueError(
            "Location must be query:name, header:name, cookie:name, form:name, "
            "json:/pointer, xml:path or body:replace"
        )
    if kind in {"query", "header", "cookie", "form"}:
        key = {"header": "headers", "cookie": "cookies"}.get(kind, kind)
        mapping = output.setdefault(key, {})
        if kind == "query":
            parsed = urlsplit(output["url"])
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            matching = [v for k, v in pairs if k == name]
            if len(matching) > 1:
                raise ValueError("Ambiguous repeated query injection location")
            mapping = {**dict(pairs), **mapping}
            output[key] = mapping
            output["url"] = urlunsplit(parsed._replace(query=""))
        if kind == "header":
            name = next((k for k in mapping if k.lower() == name.lower()), name)
        if name not in mapping:
            raise ValueError("Selected field does not exist; supply it in the request template")
        mapping[name] = value
    elif kind == "json":
        if "json" not in output:
            raise ValueError("JSON injection requires a JSON request body")
        json_pointer(output["json"], name, value)
    elif kind == "xml":
        body = output.get("xml")
        if body is None:
            raise ValueError("XML injection requires an XML request body")
        root, _ = parse_xml(body.encode())
        try:
            nodes = [root] if name == "." else root.findall(name)
        except (SyntaxError, KeyError) as exc:
            raise ValueError(
                "Unsupported XML path; use ElementTree expanded namespace paths"
            ) from exc
        if len(nodes) != 1:
            raise ValueError("XML injection location must select exactly one element")
        nodes[0].text = str(value)
        output["xml"] = ET.tostring(root, encoding="unicode")
    elif kind == "body" and name == "replace":
        for key in ("form", "json", "xml", "data", "body_base64"):
            output.pop(key, None)
        output["body"] = str(value)
    else:
        raise ValueError("Unsupported injection location")
    return validate_request(output)


def register_request_secrets(ctx, request):
    ctx.secrets.extend(header_secrets(request.get("headers", {})))
    ctx.secrets.extend(request.get("cookies", {}).values())

    def visit(item, key=""):
        if isinstance(item, dict):
            for k, v in item.items():
                visit(v, str(k))
        elif isinstance(item, list):
            for v in item:
                visit(v, key)
        elif SENSITIVE.search(key):
            ctx.secrets.append(str(item))

    visit(request)
    for k, v in parse_qsl(urlsplit(request["url"]).query):
        if SENSITIVE.search(k):
            ctx.secrets.append(v)
    if "xml" in request:
        root, _ = parse_xml(request["xml"].encode())
        for node in root.iter():
            if SENSITIVE.search(node.tag) and node.text:
                ctx.secrets.append(node.text)


def resolve_request(ctx, request):
    request = copy.deepcopy(request)
    if not ctx.targets:
        raise ValueError("Request execution requires explicit target scope")
    if not urlsplit(request["url"]).scheme and len(ctx.targets) != 1:
        raise ValueError("Relative requests require exactly one target")
    resolved = ctx.resolve(request["url"], ctx.targets[0])
    if not resolved:
        raise ValueError("Request URL is outside supplied scope")
    parsed = urlsplit(resolved)
    if request.get("query"):
        supplied = set(request["query"])
        pairs = [
            (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k not in supplied
        ]
        pairs.extend(request["query"].items())
        resolved = urlunsplit(parsed._replace(query=urlencode(pairs)))
    request["url"] = resolved
    name = request.get("profile", ctx.settings["PROFILE"])
    if name not in ctx.profiles:
        raise ValueError("Unknown request session profile")
    register_request_secrets(ctx, request)
    return request


async def execute_request(ctx, request, *, label="request", allow_entity=False):
    # The only entity-bearing requests are constructed by the bounded XXE checker.
    if not allow_entity:
        request = validate_request(request)
    request = resolve_request(ctx, request)
    headers = dict(request.get("headers", {}))
    if request.get("cookies"):
        cookie = SimpleCookie()
        for k, v in request["cookies"].items():
            cookie[k] = v
        headers["Cookie"] = "; ".join(m.OutputString() for m in cookie.values())
    data = request.get("body", request.get("data"))
    if "body_base64" in request:
        data = base64.b64decode(request["body_base64"], validate=True)
    if request.get("form") is not None:
        data = request["form"]
    elif "json" in request:
        data = json.dumps(request["json"], separators=(",", ":"))
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
    elif request.get("xml") is not None:
        data = request["xml"]
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/xml"
    started = time.monotonic()
    response = await ctx.fetch(
        request["url"],
        method=request["method"],
        headers=headers,
        data=data,
        profile=request.get("profile"),
        follow_redirects=False,
    )
    elapsed = time.monotonic() - started
    ctx.report.setdefault("requests", []).append(
        {
            "request_id": request.get("id"),
            "label": label,
            "method": request["method"],
            "url": request["url"],
            "elapsed": elapsed,
            "evidence": response.evidence_id,
        }
    )
    return response, elapsed
