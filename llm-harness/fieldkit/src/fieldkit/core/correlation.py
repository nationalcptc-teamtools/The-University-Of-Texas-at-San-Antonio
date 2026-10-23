"""Passive route, identifier, Actuator, auth-flow and artifact interpretation."""

import base64
import gzip
import io
import json
import re
import tarfile
import zipfile
import zlib
from urllib.parse import parse_qsl, urlsplit

from fieldkit.core.local_worker import CANDIDATE
from fieldkit.core.redaction import SENSITIVE
from fieldkit.core.vault import digest


def json_nodes(value, maximum=50000, depth=32):
    pending, count = [("", value, 0)], 0
    while pending:
        path, item, level = pending.pop()
        count += 1
        if count > maximum or level > depth:
            raise ValueError("JSON node/depth limit exceeded")
        yield path, item
        if isinstance(item, dict):
            pending.extend(
                (path + "/" + str(k).replace("~", "~0").replace("/", "~1"), v, level + 1)
                for k, v in reversed(list(item.items()))
            )
        elif isinstance(item, list):
            pending.extend(
                (path + "/" + str(i), v, level + 1) for i, v in reversed(list(enumerate(item)))
            )


def response_body(record):
    return base64.b64decode(
        (record["data"].get("response") or {}).get("body_base64", ""), validate=True
    )


def actuator(document, maximum=1000):
    budget = {"count": 0, "limited": False}

    class BoundedList(list):
        def append(self, value):
            if budget["count"] >= maximum:
                budget["limited"] = True
                return
            budget["count"] += 1
            super().append(value)

    routes, secrets, clues, exposures = (BoundedList() for _ in range(4))
    for pointer, value in json_nodes(document):
        if budget["limited"]:
            break
        if isinstance(value, dict):
            conditions = value.get("requestMappingConditions")
            if isinstance(conditions, dict):
                if not isinstance(conditions.get("patterns", []), list) or not isinstance(
                    conditions.get("methods", []), list
                ):
                    raise ValueError("Actuator mapping patterns/methods must be lists")
                for pattern in conditions.get("patterns", [])[:100]:
                    for method in conditions.get("methods", [])[:20] or ["ANY"]:
                        if isinstance(pattern, str) and pattern.startswith("/"):
                            routes.append(
                                {
                                    "path": pattern,
                                    "method": method,
                                    "pointer": pointer,
                                    "controller": value.get("handlerMethod"),
                                }
                            )
            predicate = value.get("predicate")
            if isinstance(predicate, str):
                method = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", predicate)
                for pattern in re.findall(r"/[A-Za-z0-9_{}./:*?-]+", predicate):
                    routes.append(
                        {
                            "path": pattern,
                            "method": method[1] if method else "ANY",
                            "pointer": pointer,
                            "controller": value.get("handler"),
                        }
                    )
            if "value" in value and SENSITIVE.search(pointer):
                candidate = value["value"]
                if isinstance(candidate, (str, int, float)) and str(candidate) not in {
                    "******",
                    "<redacted>",
                    "[REDACTED]",
                    "",
                }:
                    secrets.append(
                        {
                            "pointer": pointer,
                            "fingerprint": digest(str(candidate).encode()),
                            "confidence": "candidate",
                            "validity": "untested",
                        }
                    )
        if isinstance(value, str):
            confidential = bool(SENSITIVE.search(pointer)) and pointer.rsplit("/", 1)[-1] not in {
                "origin",
                "source",
                "description",
            }
            if confidential and value not in {"******", "<redacted>", "[REDACTED]", ""}:
                secrets.append(
                    {
                        "pointer": pointer,
                        "fingerprint": digest(value.encode()),
                        "confidence": "candidate",
                        "validity": "untested",
                    }
                )
            for match in CANDIDATE.finditer(value):
                for candidate in match.groups():
                    if candidate:
                        secrets.append(
                            {
                                "pointer": pointer,
                                "fingerprint": digest(candidate.encode()),
                                "confidence": "candidate",
                                "validity": "untested",
                            }
                        )
            if not confidential and re.search(
                r"(?i)version|artifact|dependency|jar|origin|build", pointer
            ):
                clues.append({"pointer": pointer, "value": value[:500], "confidence": "observed"})
        key = pointer.rsplit("/", 1)[-1]
        if key in {"propertySources", "beans", "mappings", "build", "git", "_links"}:
            exposures.append({"pointer": pointer, "kind": key, "status": "observed"})
    return {
        "routes": routes,
        "secrets": secrets,
        "dependencies": clues,
        "exposures": exposures,
        "coverage_limited": budget["limited"],
    }


def semantic_type(pointer, route=""):
    fields = [p for p in pointer.split("/") if p and not p.isdigit()]
    field = fields[-1] if fields else "id"
    if field.lower() in {"id", "uuid"}:
        field = fields[-2] if len(fields) > 1 else route.rstrip("/").rsplit("/", 1)[-1] or "unknown"
    field = re.sub(r"([a-z])([A-Z])", r"\1-\2", field).lower().replace("_", "-")
    field = re.sub(r"(?:-?(?:uuid|id))$", "", field)
    return field.rstrip("s") or "unknown"


def route_identifiers(document, route=""):
    for pointer, value in json_nodes(document):
        name = pointer.rsplit("/", 1)[-1]
        if (
            isinstance(value, (str, int))
            and not isinstance(value, bool)
            and len(str(value)) <= 256
            and (
                name.lower() in {"id", "uuid"} or re.search(r"(?:_id|Id|ID|_uuid|Uuid|UUID)$", name)
            )
            and not SENSITIVE.search(pointer)
        ):
            yield {
                "pointer": pointer,
                "value": value,
                "semantic_type": semantic_type(pointer, route),
                "type_confidence": "inferred_from_field",
                "fingerprint": digest(str(value).encode()),
            }


def request_values(request):
    parsed = urlsplit(request["url"])
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not SENSITIVE.search(name):
            yield "query:" + name, value
    for index, value in enumerate(parsed.path.split("/")):
        if value:
            yield "path:" + str(index), value
    for kind in ("query", "form", "json"):
        if kind in request:
            for pointer, value in json_nodes(request[kind]):
                if pointer and isinstance(value, (str, int)) and not SENSITIVE.search(pointer):
                    yield kind + ":" + pointer, str(value)


def auth_flow(record):
    request = record["data"]["request"]
    parameters = dict(parse_qsl(urlsplit(request["url"]).query))
    response = record["data"].get("response") or {}
    headers = response.get("headers", {})
    result = {
        "request": record["id"],
        "url": request["url"],
        "client_id": parameters.get("client_id"),
        "redirect_uri": parameters.get("redirect_uri"),
        "scopes": parameters.get("scope", "").split(),
        "pkce": {
            "present": "code_challenge" in parameters,
            "method": parameters.get("code_challenge_method"),
        },
        "observed_redirect": next((v for k, v in headers.items() if k.lower() == "location"), None),
        "tokens": [],
        "outcome": "observed",
    }
    material = json.dumps(request) + response_body(record).decode(errors="replace")
    for token in dict.fromkeys(
        re.findall(
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])", material
        )
    ):
        encoded = token.split(".")[1]
        if len(encoded) > 32768:
            continue
        try:
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        except (ValueError, UnicodeError, RecursionError):
            continue
        if isinstance(claims, dict):
            result["tokens"].append(
                {
                    "fingerprint": digest(token.encode()),
                    "claims": {
                        k: claims.get(k)
                        for k in ("iss", "sub", "aud", "azp", "client_id", "scope", "exp")
                        if k in claims
                    },
                    "signature_verified": False,
                    "note": "Claims are untrusted; client identity does not imply "
                    "arbitrary-user access",
                }
            )
    return result


def capture_order(source, target):
    """Traffic chronology is distinct from the date the operator imported a file."""
    if source["id"] == target["id"]:
        return None
    from datetime import datetime

    def stamp(record):
        value = (record["data"].get("response") or {}).get("timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else None
        except (ValueError, AttributeError):
            return None

    first, second = stamp(source), stamp(target)
    if first and second:
        return "capture_time_order" if first < second else None
    a, b = source["source"], target["source"]
    if a.get("file") and (a.get("file"), a.get("sha256")) == (b.get("file"), b.get("sha256")):
        if isinstance(a.get("index"), int) and isinstance(b.get("index"), int):
            return "capture_index_order" if a["index"] < b["index"] else None
    return "ordering_unknown"


def detect_format(content):
    if content.startswith(b"\xac\xed\x00\x05"):
        return "java-serialization-stream"
    if len(content) >= 2 and content[0] == 0x80 and content[1] <= 5:
        return "possible-python-pickle"
    if re.match(rb'(?:a:\d+:\{|O:\d+:"|s:\d+:"|C:\d+:"|N;)', content):
        return "possible-php-serialization"
    if content.startswith(b"PK\x03\x04"):
        return "zip"
    if content.startswith(b"\x1f\x8b"):
        return "gzip"
    if content[257:262] == b"ustar":
        return "tar"
    if content[:1] == b"x" and len(content) > 2 and (content[0] * 256 + content[1]) % 31 == 0:
        return "zlib"
    try:
        json.loads(content)
        return "json"
    except (ValueError, UnicodeError, RecursionError):
        return "opaque"


def transformations(content, maximum, max_members=100):
    try:
        yield from _transformations(content, maximum, max_members)
    except (zipfile.BadZipFile, tarfile.TarError, zlib.error, EOFError, RuntimeError) as exc:
        raise ValueError("Malformed or unsupported compressed/archive content") from exc


def _transformations(content, maximum, max_members):
    format_name = detect_format(content)
    if format_name == "zip":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > max_members:
                raise ValueError("Archive member limit exceeded")
            remaining = maximum
            for member in members:
                if member.is_dir():
                    continue
                with archive.open(member) as stream:
                    data = stream.read(remaining + 1)
                if len(data) > remaining:
                    raise ValueError("Archive decoded-byte limit exceeded")
                remaining -= len(data)
                yield "zip:" + member.filename, data
    elif format_name == "tar":
        remaining = maximum
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
            for count, member in enumerate(archive, 1):
                if count > max_members:
                    raise ValueError("Archive member limit exceeded")
                if not member.isfile():
                    continue
                if member.size > remaining:
                    raise ValueError("Archive decoded-byte limit exceeded")
                with archive.extractfile(member) as stream:
                    data = stream.read(remaining + 1)
                if len(data) > remaining:
                    raise ValueError("Archive decoded-byte limit exceeded")
                remaining -= len(data)
                yield "tar:" + member.name, data
    elif format_name == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Compression decoded-byte limit exceeded")
        yield "gzip", data
    elif format_name == "zlib":
        decoder = zlib.decompressobj()
        data = decoder.decompress(content, maximum + 1)
        if len(data) > maximum:
            raise ValueError("Compression decoded-byte limit exceeded")
        if not decoder.eof:
            raise ValueError("Truncated zlib stream")
        yield "zlib", data
    else:
        text = b"".join(content.split())
        if (
            len(text) >= 8
            and len(text) <= (maximum + 2) // 3 * 4
            and re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", text)
        ):
            try:
                decoded = base64.b64decode(text, validate=True)
            except ValueError:
                return
            if len(decoded) > maximum:
                raise ValueError("Base64 decoded-byte limit exceeded")
            if decoded and decoded != content:
                yield "base64", decoded


def library_candidates(content):
    text = content.decode(errors="replace")
    patterns = (
        r"\b([A-Za-z][A-Za-z0-9_.-]{1,80})-([0-9]+\.[0-9]+(?:\.[0-9]+)?[A-Za-z0-9._-]*)\.jar\b",
        r"\b([A-Za-z][\w.]+:[A-Za-z][\w.-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?[\w.-]*)\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            yield {
                "package": match[1],
                "version": match[2],
                "confidence": "candidate",
                "note": "Version/dependency text is not a vulnerability confirmation",
            }


def public_secret_candidates(content):
    text = content.decode(errors="replace")
    for match in CANDIDATE.finditer(text):
        for value in match.groups():
            if value:
                yield {
                    "fingerprint": digest(value.encode()),
                    "confidence": "candidate",
                    "validity": "untested",
                }
    for match in re.finditer(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]+)", text):
        yield {
            "fingerprint": digest(match[1].encode()),
            "confidence": "candidate",
            "validity": "untested",
        }

    for match in re.finditer(
        r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----", text, re.DOTALL
    ):
        yield {
            "fingerprint": digest(match[0].encode()),
            "confidence": "candidate",
            "validity": "untested",
            "kind": "private_key",
        }


def openapi_routes(document):
    if not isinstance(document, dict):
        return
    if not isinstance(document.get("servers", []), list) or not isinstance(
        document.get("paths", {}), dict
    ):
        raise ValueError("OpenAPI servers/paths have invalid types")
    servers = [s.get("url", "") for s in document.get("servers", []) if isinstance(s, dict)]
    if document.get("host"):
        servers = [
            scheme + "://" + document["host"] + document.get("basePath", "")
            for scheme in document.get("schemes", ["https"])
        ]
    for path, operations in document.get("paths", {}).items():
        for method, operation in operations.items() if isinstance(operations, dict) else []:
            if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                if operation is not None and not isinstance(operation, dict):
                    raise ValueError("OpenAPI operations must be objects")
                for server in servers or [""]:
                    yield {
                        "path": path,
                        "url": server.rstrip("/") + path if server else None,
                        "method": method.upper(),
                        "operation_id": (operation or {}).get("operationId"),
                        "parameters": (operation or {}).get("parameters", []),
                        "source_kind": "openapi",
                    }


def javascript_routes(content):
    text = content.decode(errors="replace")
    for match in re.finditer(
        r"""["'`]((?:https?://[^\s"'`]+)?/[A-Za-z0-9_{}./?&=:%-]+)["'`]""", text
    ):
        path = match[1]
        yield {
            "path": urlsplit(path).path,
            "url": path if path.startswith("http") else None,
            "method": "UNKNOWN",
            "source_kind": "javascript",
            "offset": match.start(),
            "confidence": "candidate",
            "note": "String reference may not be a callable route",
        }
