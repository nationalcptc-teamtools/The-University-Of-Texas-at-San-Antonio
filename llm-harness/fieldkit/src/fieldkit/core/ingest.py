"""Bounded passive import of HAR, Burp saved XML, raw HTTP and Fieldkit reports."""

import base64
import json
from urllib.parse import parse_qsl, urlencode, urlsplit

from fieldkit.core.replay import raw_request, validate_request
from fieldkit.core.vault import digest
from fieldkit.core.xml import parse_xml


def load_json(content):
    try:
        document = json.loads(content)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid or excessively nested captured JSON") from exc
    pending, count = [(document, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            raise ValueError("Captured JSON depth/node limit exceeded")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
    return document


def body_request(request, content, media):
    if not content:
        return request
    if "json" in media:
        request["json"] = load_json(content)
    elif "x-www-form-urlencoded" in media:
        pairs = parse_qsl(content.decode(), keep_blank_values=True)
        if len(dict(pairs)) == len(pairs):
            request["form"] = dict(pairs)
        else:
            request["body"] = content.decode()
    elif "xml" in media:
        # Preserve captured bytes. Entity-bearing bodies are opaque replay bodies,
        # never parsed while importing evidence.
        from fieldkit.core.xml import parse_xml

        try:
            parse_xml(content)
            request["xml"] = content.decode()
        except ValueError:
            request["body_base64"] = base64.b64encode(content).decode()
    else:
        try:
            request["body"] = content.decode("utf-8")
        except UnicodeError:
            request["body_base64"] = base64.b64encode(content).decode()
    return request


def captured_headers(values, *, request=False):
    if not isinstance(values, list):
        raise ValueError("Captured headers must be name/value lists")
    output, seen = {}, set()
    for header in values:
        if not isinstance(header, dict) or not all(
            isinstance(header.get(k), str) for k in ("name", "value")
        ):
            raise ValueError("Captured header names/values must be strings")
        name = header["name"]
        if request and (
            name.lower() in {"host", "content-length", "connection", "transfer-encoding"}
            or name.startswith(":")
        ):
            continue
        if request and name.lower() in seen:
            raise ValueError("Repeated captured request headers are unsupported")
        seen.add(name.lower())
        output[name] = header["value"]
    return output


def har_records(content, maximum=1000):
    document = load_json(content)
    entries = document.get("log", {}).get("entries") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR requires log.entries")
    if len(entries) > maximum:
        raise ValueError("HAR entry limit exceeded; split the capture")
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            raise ValueError("Invalid HAR entry")
        raw = entry["request"]
        headers = captured_headers(raw.get("headers", []), request=True)
        request = {
            "url": raw["url"],
            "method": raw["method"],
            "headers": headers,
            "cookies": {c["name"]: c["value"] for c in raw.get("cookies", [])},
        }
        post = raw.get("postData", {})
        if "text" in post:
            body_request(request, post["text"].encode(), post.get("mimeType", ""))
        elif post.get("params"):
            if post.get("mimeType", "") != "application/x-www-form-urlencoded":
                raise ValueError("Captured multipart reconstruction needs the original body bytes")
            if any("fileName" in p for p in post["params"]):
                raise ValueError("HAR multipart file reconstruction is unsupported")
            pairs = [(p["name"], p.get("value", "")) for p in post["params"]]
            request["body"] = urlencode(pairs)
            headers.setdefault("Content-Type", post["mimeType"])
        response = entry.get("response", {})
        body = response.get("content", {})
        text = body.get("text", "")
        data = (
            base64.b64decode(text, validate=True)
            if body.get("encoding") == "base64"
            else text.encode()
        )
        metadata = {
            "ip": entry.get("serverIPAddress"),
            "observed_host_header": next(
                (h["value"] for h in raw.get("headers", []) if h["name"].lower() == "host"), None
            ),
        }
        yield (
            validate_request(request),
            {
                "status": response.get("status"),
                "headers": captured_headers(response.get("headers", [])),
                "headers_raw": response.get("headers", []),
                "body_base64": base64.b64encode(data).decode(),
                "mime_type": body.get("mimeType"),
                "timestamp": entry.get("startedDateTime"),
            },
            index,
            metadata,
        )


def raw_response(content):
    head, _, body = content.partition(b"\r\n\r\n")
    if b"\r\n" not in head:
        head, _, body = content.partition(b"\n\n")
    lines = head.decode(errors="replace").splitlines()
    parts = lines[0].split() if lines else []
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip()] = value.strip()
    return {
        "status": status,
        "headers": headers,
        "body_base64": base64.b64encode(body).decode(),
        "mime_type": next((v for k, v in headers.items() if k.lower() == "content-type"), ""),
    }


def burp_records(content, maximum=1000):
    root, _ = parse_xml(content, max_bytes=len(content))
    if root.tag != "items":
        raise ValueError("Burp saved items XML requires an items root")
    items = root.findall("item")
    if len(items) > maximum:
        raise ValueError("Burp entry limit exceeded; split the capture")
    for index, item in enumerate(items, 1):
        url = item.findtext("url")
        node = item.find("request")
        if node is None or not url:
            raise ValueError("Burp item is missing URL/request")
        raw = (
            base64.b64decode(node.text or "", validate=True)
            if node.get("base64") == "true"
            else (node.text or "").encode()
        )
        # HTTP/2 exports still have ordinary method/path/header semantics here.
        raw = raw.replace(b" HTTP/2\r\n", b" HTTP/1.1\r\n", 1)
        parsed = urlsplit(url)
        request = raw_request(raw, f"{parsed.scheme}://{parsed.netloc}")
        response_node = item.find("response")
        response = None
        if response_node is not None:
            data = (
                base64.b64decode(response_node.text or "", validate=True)
                if response_node.get("base64") == "true"
                else (response_node.text or "").encode()
            )
            response = raw_response(data)
            response["timestamp"] = item.findtext("time")
        host = item.find("host")
        yield (
            request,
            response,
            index,
            {
                "ip": host.get("ip") if host is not None else None,
                "burp_host": item.findtext("host"),
            },
        )


def ingest(
    vault, content, format_name, filename, *, maximum=1000, tags=None, context=None, raw_url=""
):
    source = {"file": str(filename), "sha256": digest(content), "format": format_name}
    asset = vault.context_asset((context or {}).get("host", ""))
    if format_name == "har":
        records = har_records(content, maximum)
    elif format_name == "burp":
        records = burp_records(content, maximum)
    elif format_name == "raw":
        records = [(raw_request(content, raw_url), None, 1, {})]
    else:
        if format_name in {"js", "artifact"}:
            return [vault.artifact(content, source=source, asset=asset)]
        document = load_json(content)
        if format_name == "report":
            if not isinstance(document, dict):
                raise ValueError("Fieldkit report must be an object")
            for collection in ("evidence", "endpoints", "findings", "results"):
                values = document.get(collection, [])
                if not isinstance(values, list) or len(values) > maximum:
                    raise ValueError("Report collections must be lists within the record limit")
                if not all(isinstance(row, dict) for row in values):
                    raise ValueError("Report records must be objects")
        identifier = vault.put(
            "document",
            {
                "format": format_name,
                "source": source,
                "private_raw": True,
                "asset": asset,
            },
            private={
                "format": format_name,
                "document": document,
                "asset": asset,
            },
            source=source,
        )
        imported = [identifier]
        if format_name == "report":
            references = {}
            for evidence in document.get("evidence", []):
                entry = vault.put(
                    "observation",
                    {"kind": "imported_evidence_reference", **evidence, "raw_imported": False},
                    source=source,
                )
                if evidence.get("id"):
                    references[evidence["id"]] = entry
                vault.link(identifier, entry, "report_evidence_reference")
                imported.append(entry)
            for collection, kind in (
                ("endpoints", "route"),
                ("findings", "finding"),
                ("results", "observation"),
            ):
                for row in document.get(collection, [])[:maximum]:
                    row = dict(row)
                    if isinstance(row.get("evidence"), list):
                        row["evidence"] = [references.get(r, r) for r in row["evidence"]]
                    entry = vault.put(kind, row, source=source)
                    vault.link(identifier, entry, "report_record")
                    imported.append(entry)
        return imported
    imported = []
    # Parse the bounded capture completely before persisting any exchanges.
    for request, response, index, metadata in list(records):
        identifier = vault.exchange(
            request,
            response,
            source={**source, "index": index},
            tags=tags,
            context=context,
            metadata=metadata,
        )
        imported.append(identifier)
    return imported
