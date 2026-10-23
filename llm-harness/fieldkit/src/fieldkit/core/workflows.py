"""Bounded HTML/JSON token extraction and named variable substitution."""

import json
import re
from html import escape
from html.parser import HTMLParser
from urllib.parse import quote


def extract_value(response, specification):
    source = specification.get("source")
    if source == "json":
        try:
            value = json.loads(response.body)
            pointer = specification["pointer"]
            if not isinstance(pointer, str) or not pointer.startswith("/"):
                raise ValueError("JSON extractor requires /path pointer")
            for token in pointer[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                value = value[int(token)] if isinstance(value, list) else value[token]
        except (ValueError, KeyError, IndexError, TypeError, RecursionError) as exc:
            raise ValueError("JSON token extraction failed") from exc
    elif source == "html":
        tag = specification.get("tag", "input")
        attribute = specification.get("attribute", "value")
        matching = specification.get("match", {})
        if not isinstance(matching, dict) or not matching:
            raise ValueError("HTML extractor requires an attribute match object")
        values = []

        class Extractor(HTMLParser):
            def handle_starttag(self, name, attrs):
                attrs = dict(attrs)
                if name == tag and all(attrs.get(k) == v for k, v in matching.items()):
                    if attribute in attrs and attrs[attribute] is not None:
                        values.append(attrs[attribute])

        parser = Extractor()
        parser.feed(response.body.decode("utf-8", errors="replace"))
        if len(values) != 1:
            raise ValueError("HTML extractor must match exactly one value")
        value = values[0]
    else:
        raise ValueError("Supported token sources are html and json")
    if not isinstance(value, (str, int, float, bool)) or value == "" or len(str(value)) > 8192:
        raise ValueError("Extracted variable must be a nonempty bounded scalar")
    return str(value)


def substitute(value, variables, key=""):
    if isinstance(value, dict):
        return {k: substitute(v, variables, k) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables, key) for v in value]
    if not isinstance(value, str):
        return value

    def replace(match):
        name = match[1]
        if name not in variables:
            raise ValueError(f"Missing workflow variable: {name}")
        result = str(variables[name])
        if key == "xml":
            return escape(result, quote=True)
        if key == "url":
            return quote(result, safe="")
        return result

    return re.sub(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", replace, value)


def profile_document(ctx, profile, name):
    client = ctx.session(profile)
    session = ctx.profiles[profile]
    return {
        "profiles": {
            name: {
                "origins": list(ctx.targets),
                "headers": session.headers,
                "cookies": {},
                "cookie_jar": [
                    {
                        "name": c.name,
                        "value": c.value,
                        "domain": c.domain,
                        "path": c.path,
                        "secure": c.secure,
                        "expires": c.expires,
                    }
                    for c in client.cookies.jar
                ],
            }
        }
    }
